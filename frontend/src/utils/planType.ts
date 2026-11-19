import catalog from '@/constants/openaiPlanTypes.builtin.json'

/** Native-owned SKU/alias/label data. Other providers own their own labels. */
export function normalizePlanType(value?: string | null): string {
  return (value || '').trim().toLowerCase().replace(/[\s_-]+/g, '')
}

/** Canonical comparison key; labels may be shared by distinct SKUs. */
export function openAIPlanTypeKey(value?: string | null): string {
  const key = normalizePlanType(value)
  const aliases = catalog.aliases as Record<string, string>
  return Object.prototype.hasOwnProperty.call(aliases, key) ? aliases[key]! : key
}

export const openAIPlanTypes: readonly string[] = catalog.plans.map((plan) => plan.code)

/** Keep Status SKU names distinct from the account families used in analytics. */
export function openAIPlanTypeLabel(value?: string | null, display: 'status' | 'analytics' = 'status'): string {
  const key = openAIPlanTypeKey(value)
  return catalog.plans.find((plan) => plan.key === key)?.[display] ?? ''
}
