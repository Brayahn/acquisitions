import logger from '#config/logger.js';
import bcrypt from 'bcrypt';
import { db } from '#config/database.js';
import { users } from '#models/user.model.js';
import { eq } from 'drizzle-orm';

export const hashPassword = async (password) => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (e) {
    logger.error(`Error Hashing the Password: ${e}`);
    throw new Error('Error Hashing');
  }
};

export const createUser = async ({name, email, password, role})=> {
  try {
    const existingUser = await db.select().from(users).where(eq(users.email, email)).limit(1);

    if (existingUser.length > 0) throw new Error('User already exists');

    const password_hash = await hashPassword(password);

    const [newUser] = await db
      .insert(users)
      .values({name, email, password: password_hash, role})
      .returning({
        id: users.id, 
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at   
      });

    logger.info(`User ${email} created successfully`);

    return newUser;


  } catch (e) {
    logger.error(`Error creeating the user: ${e}`);
    throw e;
  }
};

export const comparePassword = async (password, hashedPassword) => {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (e) {
    logger.error(`Error Comparing the Password: ${e}`);
    throw new Error('Error Comparing Password');
  }
};

export const authenticateUser = async ({ email, password }) => {
  try {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (!user) {
      throw new Error('Invalid email or password');
    }

    const isMatch = await comparePassword(password, user.password);

    if (!isMatch) {
      throw new Error('Invalid email or password');
    }

    logger.info(`User ${email} authenticated successfully`);

    return user;
  } catch (e) {
    if (e.message === 'Invalid email or password') {
      logger.warn(`Failed login attempt for ${email}: ${e.message}`);
      throw e;
    }

    logger.error(`Error authenticating the user: ${e}`);
    throw e;
  }
};
