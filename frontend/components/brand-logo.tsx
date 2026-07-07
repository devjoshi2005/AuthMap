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
    sm: "text-3xl",
    md: "text-4xl",
    lg: "text-5xl",
    xl: "text-[3.6rem]",
  } as const;

  const content = (
    <span
      className={[
        "inline-flex items-center align-middle font-semibold tracking-[-0.06em] text-white auth-title-glow",
        sizeMap[resolvedSize],
        className,
      ].join(" ")}
    >
      AuthMap
    </span>
  );

  if (!linked) {
    return content;
  }

  return <Link href={href}>{content}</Link>;
}
