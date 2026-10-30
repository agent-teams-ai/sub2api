import { describe, expect, it } from 'vitest'
import * as XLSX from 'xlsx'

// Exercises the real dependency: mocked UsageView tests cannot detect corrupt exports.
describe('usage workbook serialization contract', () => {
  it('preserves appended pages, Unicode, numbers and literal strings in an XLSX file', () => {
    const headers = ['Time', 'Account', 'Tokens', 'Cost', 'Request ID']
    const firstPage = ['2026-10-07T15:00:00Z', 'Організація 日本語', 1234, '0.001234', '=1+1']
    const secondPage = ['2026-10-07T15:01:00Z', 'Second account', 0, '0.000000', 'request-2']
    const sheet = XLSX.utils.aoa_to_sheet([headers])
    XLSX.utils.sheet_add_aoa(sheet, [firstPage], { origin: -1 })
    XLSX.utils.sheet_add_aoa(sheet, [secondPage], { origin: -1 })
    const workbook = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(workbook, sheet, 'Usage')

    const bytes = new Uint8Array(XLSX.write(workbook, { bookType: 'xlsx', type: 'array' }))
    expect([...bytes.slice(0, 4)]).toEqual([0x50, 0x4b, 0x03, 0x04])
    const decoded = XLSX.read(bytes, { type: 'array' })
    expect(decoded.SheetNames).toEqual(['Usage'])
    const output = decoded.Sheets.Usage!
    expect(XLSX.utils.sheet_to_json(output, { header: 1 })).toEqual([headers, firstPage, secondPage])
    expect(output.C2).toMatchObject({ t: 'n', v: 1234 })
    expect(output.D2).toMatchObject({ t: 's', v: '0.001234' })
    expect(output.E2).toMatchObject({ t: 's', v: '=1+1' })
    expect(output.E2.f).toBeUndefined()
  })
})
