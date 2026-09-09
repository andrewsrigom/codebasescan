import type { CSSProperties, ReactNode } from 'react';
const shapes = {
  shield: (
    <>
      <path d="M12 3 20 6v6c0 4-5 8-8 9-3-1-8-5-8-9V6l8-3Z" />
      <path d="m8 12 3 3 5-6" />
    </>
  ),
  grid: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </>
  ),
  scan: (
    <>
      <path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5M3 12h18" />
    </>
  ),
  folder: <path d="M3 6a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v10H3V6Z" />,
  layers: (
    <>
      <path d="m12 3 10 5-10 5L2 8l10-5Z" />
      <path d="m2 12 10 5 10-5m-20 9 10 5 10-5" transform="translate(0 -3)" />
    </>
  ),
  settings: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="m9 3-.5 3-3 1-2.5-1-1 3 2 2v3l-2 2 1 3 3-1 2 1 1 3h4l1-3 2-1 3 1 1-3-2-2v-3l2-2-1-3-3 1-3-1-.5-3Z" />
    </>
  ),
  book: (
    <>
      <path d="M12 5v15M3 4c3-1 6-1 9 1 3-2 6-2 9-1v15c-3-1-6-1-9 1-3-2-6-2-9-1V4Z" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="10" width="14" height="11" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" />
    </>
  ),
  arrow: (
    <>
      <path d="M5 12h14m-5-5 5 5-5 5" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
  check: <path d="m5 12 4 4L19 6" />,
  close: <path d="m6 6 12 12M6 18 18 6" />,
  search: (
    <>
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="m16 16 5 5" />
    </>
  ),
  alert: (
    <>
      <path d="m12 3 10 18H2L12 3Z" />
      <path d="M12 9v5m0 3v.1" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  code: (
    <>
      <path d="m8 6-6 6 6 6m8-12 6 6-6 6M14 3l-4 18" />
    </>
  ),
  download: (
    <>
      <path d="M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4" />
    </>
  ),
  branch: (
    <>
      <circle cx="6" cy="4" r="2" />
      <circle cx="6" cy="20" r="2" />
      <circle cx="18" cy="6" r="2" />
      <path d="M6 6v12m0-6h6a6 6 0 0 0 6-4" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v6m0-10v.1" />
    </>
  ),
  terminal: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="m6 9 3 3-3 3m6 0h5" />
    </>
  ),
} satisfies Record<string, ReactNode>;
export function Icon({
  name,
  size = 18,
  style,
}: {
  name: keyof typeof shapes;
  size?: number;
  style?: CSSProperties;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      style={style}
    >
      {shapes[name]}
    </svg>
  );
}
