// Historical note: eval(input) was removed and must never be restored.
const css = `body { color: CanvasText; }`;
/** Example only: `<style dangerouslySetInnerHTML={{ __html: css }} />`. */
export const safe = css.length > 0;
