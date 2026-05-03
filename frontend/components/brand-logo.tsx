import Link from "next/link";

type BrandLogoProps = {
  href?: string;
  className?: string;
  compact?: boolean;
  linked?: boolean;
  size?: "sm" | "md" | "lg" | "xl";
};

export function BrandLogo({
  href = "/welcome",
  className = "",
  compact = false,
  linked = true,
  size = "md",
}: BrandLogoProps) {
  const resolvedSize = compact ? "sm" : size;

  const sizeMap = {
    sm: {
      wrapper: "gap-0",
      box: "px-4 py-2",
      ai: "px-3.25 py-2",
      text: "text-[1.42rem]",
    },
    md: {
      wrapper: "gap-0",
      box: "px-5 py-2.5",
      ai: "px-3.75 py-2.5",
      text: "text-[2.18rem] sm:text-[2.34rem]",
    },
    lg: {
      wrapper: "gap-0",
      box: "px-6 py-3",
      ai: "px-4.5 py-3",
      text: "text-[2.72rem] sm:text-[2.98rem]",
    },
    xl: {
      wrapper: "gap-0",
      box: "px-7 py-3.5",
      ai: "px-5.5 py-3.5",
      text: "text-[3.28rem] sm:text-[3.72rem]",
    },
  } as const;

  const currentSize = sizeMap[resolvedSize];

  const content = (
    <span
      className={[
        "inline-flex items-stretch overflow-hidden uppercase leading-none align-middle",
        currentSize.wrapper,
        className,
      ].join(" ")}
    >
      <span
        className={[
          "inline-flex items-center justify-center bg-white text-[#0a0a0a]",
          currentSize.box,
        ].join(" ")}
      >
        <span
          className={[
            "font-black leading-none tracking-[-0.05em]",
            currentSize.text,
          ].join(" ")}
          style={{
            fontFamily: '"Helvetica Neue", Helvetica, Arial, sans-serif',
            textShadow: "0 1px 0 rgba(255,255,255,0.65), 0 0 16px rgba(0,0,0,0.12)",
          }}
        >
          BOX
        </span>
      </span>

      <span
        className={[
          "inline-flex items-center justify-center bg-[#0d1025] text-white",
          currentSize.ai,
        ].join(" ")}
      >
        <span
          className={[
            "font-black leading-none tracking-[-0.05em] text-white",
            currentSize.text,
          ].join(" ")}
          style={{
            fontFamily: '"Helvetica Neue", Helvetica, Arial, sans-serif',
            textShadow: "0 0 16px rgba(255,255,255,0.3), 0 0 30px rgba(122,157,255,0.18)",
          }}
        >
          AI
        </span>
      </span>
    </span>
  );

  if (!linked) {
    return content;
  }

  return <Link href={href}>{content}</Link>;
}