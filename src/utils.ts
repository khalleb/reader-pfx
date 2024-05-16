export function isNotNull(valor: string | null | undefined): boolean {
  return valor !== null && valor !== undefined && valor?.trim()?.length > 0;
}