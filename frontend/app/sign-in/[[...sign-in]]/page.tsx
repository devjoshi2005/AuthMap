import { SignIn } from "@clerk/nextjs";

import { AuthPageShell } from "@/components/auth-page-shell";
import { clerkAppearance } from "@/lib/clerk-appearance";

export default function SignInPage() {
  return (
    <AuthPageShell
      title="Return to the AuthMap console"
      description="Sign in to access your IAM attack path analysis, privilege escalation findings, and compliance reports. Your workspace state persists across sessions."
      alternateHref="/sign-up"
      alternateLabel="Need an account? Create one"
    >
      <SignIn
        path="/sign-in"
        routing="path"
        signUpUrl="/sign-up"
        fallbackRedirectUrl="/guide"
        appearance={clerkAppearance}
      />
    </AuthPageShell>
  );
}