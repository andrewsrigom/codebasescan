export async function POST() {
  try {
    return await fetch('https://service.example/data');
  } catch {}
}
