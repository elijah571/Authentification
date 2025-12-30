import bcrypt from 'bcryptjs';

export async function hashPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(12);
  return bcrypt.hash(password, salt);
}

export async function checkPassword(password: string, hash: string) {
  return bcrypt.compare(password, hash);
}
