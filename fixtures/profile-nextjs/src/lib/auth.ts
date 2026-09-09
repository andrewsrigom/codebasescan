export async function requireUser() {
  return getServerSession();
}

export async function requireRole(role: string) {
  const user = await requireUser();
  return hasPermission(user, role);
}
