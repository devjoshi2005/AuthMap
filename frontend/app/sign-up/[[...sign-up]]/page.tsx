import { SignUp } from "@clerk/nextjs";

import { AuthPageShell } from "@/components/auth-page-shell";
import { clerkAppearance } from "@/lib/clerk-appearance";

export default function SignUpPage() {
  return (
    <AuthPageShell
      title="Create your AuthMap account"
      description="Sign up to start mapping IAM relationships, detecting privilege escalation paths, and correlating cost waste with security risk across your cloud infrastructure."
      alternateHref="/sign-in"
      alternateLabel="Already registered? Log in"
    >
      <SignUp
        path="/sign-up"
        routing="path"
        signInUrl="/sign-in"
        fallbackRedirectUrl="/scan-wizard"
        forceRedirectUrl="/scan-wizard"
        appearance={clerkAppearance}
      />
    </AuthPageShell>
  );
}
