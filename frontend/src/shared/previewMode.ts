export function isReadOnlyPreview(): boolean {
  return (
    document.querySelector(
      'meta[name="tunnelminion-read-only-preview"][content="true"]',
    ) !== null
  );
}
