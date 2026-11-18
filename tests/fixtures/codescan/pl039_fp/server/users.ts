import bcrypt from "bcryptjs";
export async function create(db: any, users: any, email: string, password: string) {
  const hash = await bcrypt.hash(password, 12);
  await db.insert(users).values({ email, password: hash });
}
export async function login(prisma: any, email: string, password: string) {
  const u = await prisma.user.findFirst({ where: { email } });
  return u && (await bcrypt.compare(password, u.password));
}
export async function setPw(prisma: any, id: string, password: string) {
  await prisma.user.update({ where: { id }, data: { password: await bcrypt.hash(password, 12) } });
}
