/** Windows chmod does not restrict files written through the WSL UNC provider. */
export function assertPrivateSidecarDestination(
  destination: string,
  platform: NodeJS.Platform = process.platform,
): void {
  if (platform === 'win32' && /^\\\\(?:wsl\.localhost|wsl\$)\\/i.test(destination))
    throw new Error(
      'Windows cannot enforce private file permissions on WSL UNC paths. Run CodebaseScan inside WSL to write this sidecar.',
    );
}
