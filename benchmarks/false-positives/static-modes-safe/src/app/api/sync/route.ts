export async function POST() {
  try {
    return await fetch('https://service.example/data', {
      signal: AbortSignal.timeout(5000),
    });
  } catch (error) {
    throw new Error('Sync failed', { cause: error });
  }
}
