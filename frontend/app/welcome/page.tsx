import { auth } from "@clerk/nextjs/server";

import { AuthLanding } from "../../components/auth-landing";

export default async function WelcomePage() {
  const { userId } = await auth();

  return <AuthLanding isSignedIn={Boolean(userId)} />;
}