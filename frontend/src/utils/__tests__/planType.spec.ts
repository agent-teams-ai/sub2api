import { describe, expect, it } from 'vitest'
import { openAIPlanTypeKey, openAIPlanTypeLabel } from '../planType'

describe('native-owned OpenAI plan display', () => {
  it('uses native aliases and preserves distinct display contexts', () => {
    expect(openAIPlanTypeKey(' ChatGPT Pro ')).toBe('pro')
    expect(openAIPlanTypeLabel('ChatGPT Pro')).toBe('Pro 200')
    expect(openAIPlanTypeLabel('business')).toBe('Enterprise')
    expect(openAIPlanTypeLabel('business', 'analytics')).toBe('Business')
  })

  it('keeps prototype names and unknown plans as ordinary string keys', () => {
    for (const code of ['constructor', '__proto__', 'toString', 'future-tier']) {
      const key = openAIPlanTypeKey(code)
      expect(typeof key).toBe('string')
      expect(openAIPlanTypeLabel(code)).toBe('')
    }
    expect(openAIPlanTypeKey('constructor')).toBe('constructor')
  })
})
