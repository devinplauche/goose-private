export function WarMachine({ className = '' }) {
  return (
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <path
        d="M4 5 L8.5 19 L12 11.5 L15.5 19 L20 5"
        stroke="currentColor"
        strokeWidth="2.6"
        strokeLinejoin="miter"
        strokeLinecap="square"
      />
    </svg>
  );
}
