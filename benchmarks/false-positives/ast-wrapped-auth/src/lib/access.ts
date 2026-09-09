export async function requireProjectAccess() {
  return requireUser();
}

async function requireUser() {
  return getServerSession();
}
