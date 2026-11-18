export async function check(prisma, email, password) {
  return prisma.user.findFirst({ where: { email, password } });
}
