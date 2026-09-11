export function evaluateTrustedExpression(expression: string): unknown {
  return eval(expression);
}
