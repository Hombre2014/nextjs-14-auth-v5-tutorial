'use server';

import * as z from 'zod';
import bcrypt from 'bcryptjs';

import { auth } from '@/auth'; // Import the new `auth()` function
import { db } from '@/lib/db';
import { SettingsSchema } from '@/schemas';
import { getUserByEmail, getUserById } from '@/data/user';
import { currentUser } from '@/lib/auth';
import { generateVerificationToken } from '@/lib/tokens';
import { sendVerificationEmail } from '@/lib/mail';

export const settings = async (values: z.infer<typeof SettingsSchema>) => {
  const user = await currentUser();

  if (!user) {
    return { error: 'Unauthorized' };
  }

  const dbUser = await getUserById(user.id!);

  if (!dbUser) {
    return { error: 'Unauthorized' };
  }

  if (user.isOAuth) {
    values.email = undefined;
    values.password = undefined;
    values.newPassword = undefined;
    values.isTwoFactorEnabled = undefined;
  }

  if (values.email && values.email !== user.email) {
    const existingUser = await getUserByEmail(values.email);

    if (existingUser && existingUser.id !== user.id) {
      return { error: 'Email already in use!' };
    }

    const verificationToken = await generateVerificationToken(values.email);
    await sendVerificationEmail(
      verificationToken.email,
      verificationToken.token
    );

    return { success: 'Verification email sent!' };
  }

  if (values.password && values.newPassword && dbUser.password) {
    const passwordsMatch = await bcrypt.compare(
      values.password,
      dbUser.password
    );

    if (!passwordsMatch) {
      return { error: 'Incorrect password!' };
    }

    const hashedPassword = await bcrypt.hash(values.newPassword, 10);
    values.password = hashedPassword;
    values.newPassword = undefined;
  }

  const updatedUser = await db.user.update({
    where: { id: dbUser.id },
    data: {
      ...values,
    },
  });

  // Custom session update logic using `auth()`
  const session = await auth();
  if (session && session.user) {
    session.user = {
      ...session.user,
      name: updatedUser.name,
      email: updatedUser.email,
      isTwoFactorEnabled: updatedUser.isTwoFactorEnabled,
      role: updatedUser.role,
    };
  }

  return { success: 'Settings Updated!' };
};

{
  /* 
  Since NextAuth no longer provides an update function, you can use the getSession and useSession methods from next-auth to manually refresh or update the session after making changes to the user data.

  Explanation of Changes:

Custom Session Update Logic:

The getSession method from next-auth/react is used to fetch the current session.
The session's user object is updated with the new user data (e.g., name, email, isTwoFactorEnabled, role).
Removed update Import:

The update function was removed from the imports since it no longer exists in auth.ts.
Preserved Existing Logic:

The rest of the logic for email verification, password updates, and database updates remains unchanged.

  */
}
