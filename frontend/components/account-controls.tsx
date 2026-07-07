"use client";

import {
  UserAvatar,
  useClerk,
  useReverification,
  useSession,
  useUser,
} from "@clerk/nextjs";
import { isReverificationCancelledError } from "@clerk/nextjs/errors";
import { useState } from "react";

type AccountControlsProps = {
  accountLabel: string;
};

export function AccountControls({ accountLabel }: AccountControlsProps) {
  const clerk = useClerk();
  const { session } = useSession();
  const [isSigningOut, setIsSigningOut] = useState(false);

  async function handleSignOut() {
    if (isSigningOut) {
      return;
    }

    setIsSigningOut(true);

    try {
      if (session) {
        await session.remove();
      } else {
        await clerk.setActive({ session: null });
      }

      window.location.replace("/");
    } catch (error) {
      console.error(error);
      setIsSigningOut(false);
    }
  }

  function handleOpenAccount() {
    clerk.openUserProfile();
  }

  return (
    <div className="flex w-full flex-wrap items-center justify-center gap-3 self-start rounded-[1.5rem] border border-white/10 bg-[rgba(255,255,255,0.03)] px-4 py-4 text-center shadow-[0_16px_38px_rgba(0,0,0,0.16)] backdrop-blur-xl lg:self-auto xl:justify-end xl:text-left">
      <div className="min-w-[14rem] pr-0 xl:pr-2">
        <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
          Workspace access
        </p>
        <p className="mt-1 text-lg font-semibold text-white sm:text-xl">
          Welcome: {accountLabel}
        </p>
      </div>
      <button
        type="button"
        onClick={handleOpenAccount}
        className="action-box action-box-ghost px-4 py-3 text-sm font-semibold uppercase tracking-[0.16em] text-white"
      >
        Account
      </button>
      <button
        type="button"
        onClick={handleSignOut}
        disabled={isSigningOut}
        className="action-box action-box-ghost px-4 py-3 text-sm font-semibold uppercase tracking-[0.16em] text-white disabled:cursor-not-allowed disabled:opacity-60"
      >
        {isSigningOut ? "Logging out..." : "Log out"}
      </button>
      <UserAvatar
        rounded={false}
        appearance={{
          elements: {
            avatarBox: "h-11 w-11 rounded-[1rem] border border-white/10 bg-white/[0.05]",
          },
        }}
      />
    </div>
  );
}

export function AccountDangerZone() {
  const { user } = useUser();
  const [isDeleting, setIsDeleting] = useState(false);
  const deleteAccount = useReverification(async () => {
    await user?.delete();
  });

  async function handleDeleteAccount() {
    if (!user || isDeleting) {
      return;
    }

    const confirmed = window.confirm(
      "Delete your AuthMap account permanently? This removes your Clerk identity and signs you out immediately.",
    );

    if (!confirmed) {
      return;
    }

    setIsDeleting(true);

    try {
      await deleteAccount();
      localStorage.removeItem(`authmap:workspace:${user.id}`);
      window.location.replace("/");
    } catch (error) {
      if (isReverificationCancelledError(error)) {
        setIsDeleting(false);
        return;
      }

      console.error(error);
      setIsDeleting(false);
    }
  }

  return (
    <div className="flex flex-col gap-4 rounded-[1.8rem] border border-[color-mix(in_srgb,var(--accent-magenta)_32%,transparent)] bg-[linear-gradient(180deg,rgba(203,142,119,0.1),rgba(255,255,255,0.03))] p-5 shadow-[0_18px_40px_rgba(0,0,0,0.18)] sm:flex-row sm:items-center sm:justify-between">
      <div>
        <p className="font-[family:var(--font-plex-mono)] text-[0.7rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-magenta)]">
          Danger zone
        </p>
        <p className="mt-2 max-w-2xl text-sm leading-7 text-slate-300">
          Imported IAM configs and analysis state are retained per signed-in account in this browser. Deleting the account removes the Clerk identity permanently.
        </p>
      </div>
      <button
        type="button"
        onClick={handleDeleteAccount}
        disabled={isDeleting || !user}
        className="action-box action-box-magenta px-4 py-3 text-sm font-semibold uppercase tracking-[0.16em] text-white disabled:cursor-not-allowed disabled:opacity-60"
      >
        {isDeleting ? "Deleting..." : "Delete account"}
      </button>
    </div>
  );
}