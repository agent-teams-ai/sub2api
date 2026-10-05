// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia, type Pinia } from 'pinia'
import { defineComponent, h, nextTick, ref } from 'vue'
import { mount, type VueWrapper } from '@vue/test-utils'
import type { driver, Driver, DriveStep } from 'driver.js'
import AppLayout from '@/components/layout/AppLayout.vue'
import { useOnboardingTour } from '@/composables/useOnboardingTour'
import { useAuthStore } from '@/stores/auth'
import { useAdminComplianceStore } from '@/stores/adminCompliance'
import { useOnboardingStore } from '@/stores/onboarding'
import complianceAPI, {
  type AdminComplianceStatus
} from '@/api/admin/compliance'
import { getAdminSteps, getUserSteps } from '@/components/Guide/steps'

const driverMock = vi.hoisted(() => ({
  create: vi.fn<typeof driver>(),
  drive: vi.fn<Driver['drive']>()
}))

vi.mock('driver.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('driver.js')>()
  return { ...actual, driver: driverMock.create }
})

vi.mock('@/stores', () => ({
  useAppStore: () => ({ sidebarCollapsed: false })
}))

vi.mock('@/stores/auth', async () => {
  const { reactive } = await import('vue')
  const auth = reactive({
    user: { id: 1, role: 'admin' as 'admin' | 'user' },
    isSimpleMode: false
  })
  return { useAuthStore: () => auth }
})

vi.mock('@/api/admin/compliance', () => ({
  default: {
    getStatus: vi.fn(),
    accept: vi.fn()
  }
}))

vi.mock('@/i18n', () => ({
  getLocale: () => 'en'
}))

vi.mock('vue-i18n', () => ({
  useI18n: () => ({ t: (key: string) => key })
}))

vi.mock('@/components/Guide/steps', () => ({
  getAdminSteps: vi.fn(() => [
    { element: '#tour-start' }
  ] satisfies DriveStep[]),
  getUserSteps: vi.fn(() => [
    { element: '#tour-start' }
  ] satisfies DriveStep[])
}))

vi.mock('@/components/layout/AppSidebar.vue', () => ({
  default: { render: () => null }
}))

vi.mock('@/components/layout/AppHeader.vue', () => ({
  default: { render: () => null }
}))

function status(required: boolean): AdminComplianceStatus {
  return {
    required,
    version: 'v2026.06.10',
    document_path_zh: 'docs/legal/admin-compliance.zh.md',
    document_path_en: 'docs/legal/admin-compliance.en.md',
    document_url_zh:
      'https://github.com/Wei-Shaw/sub2api/blob/main/docs/legal/admin-compliance.zh.md',
    document_url_en:
      'https://github.com/Wei-Shaw/sub2api/blob/main/docs/legal/admin-compliance.en.md',
    ack_phrase_zh: '我已阅读、理解并同意 Sub2API 部署与运营合规承诺',
    ack_phrase_en:
      'I have read, understood, and agree to the Sub2API Deployment and Operation Compliance Commitment'
  }
}

describe('AppLayout compliance and onboarding startup', () => {
  let pinia: Pinia
  const views: VueWrapper[] = []

  function layout(showTarget = ref(true)): VueWrapper {
    const view = mount(AppLayout, {
      attachTo: document.body,
      global: { plugins: [pinia] },
      slots: {
        default: () => showTarget.value
          ? h('div', { id: 'tour-start' })
          : null
      }
    })
    views.push(view)
    return view
  }

  async function fetchStatus(required: boolean): Promise<void> {
    vi.mocked(complianceAPI.getStatus).mockResolvedValueOnce(status(required))
    await useAdminComplianceStore().fetchStatus()
    await nextTick()
  }

  function hook(canStart: () => boolean = () => true) {
    const captured: { tour?: ReturnType<typeof useOnboardingTour> } = {}
    const view = mount(defineComponent({
      setup() {
        captured.tour = useOnboardingTour({
          autoStart: false,
          canStart
        })
        return () => h('div')
      }
    }), {
      attachTo: document.body,
      global: { plugins: [pinia] }
    })
    views.push(view)

    const tour = captured.tour
    if (!tour) throw new Error('Missing mounted tour')
    return { view, tour }
  }

  beforeEach(async () => {
    const actual = await vi.importActual<typeof import('driver.js')>('driver.js')

    vi.useFakeTimers()
    vi.clearAllMocks()

    driverMock.create.mockImplementation((options) => {
      const original = actual.driver(options)
      let active = false
      const instance: Driver = {
        ...original,
        drive: (index) => {
          active = true
          driverMock.drive(index)
        },
        isActive: () => active,
        destroy: () => {
          active = false
          const config = original.getConfig()
          config.onDestroyed?.(
            undefined,
            config.steps?.[0] ?? {},
            { config, state: original.getState(), driver: instance }
          )
        }
      }
      return instance
    })

    vi.mocked(complianceAPI.getStatus).mockReset()
    vi.mocked(complianceAPI.accept).mockReset()
    localStorage.clear()
    document.body.replaceChildren()

    pinia = createPinia()
    setActivePinia(pinia)

    const user = useAuthStore().user
    if (!user) throw new Error('Missing test user')
    user.role = 'admin'

    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect')
      .mockImplementation(() => new DOMRect(0, 0, 100, 30))
  })

  afterEach(() => {
    useOnboardingStore().getDriverInstance()?.destroy()
    for (const view of views.splice(0)) view.unmount()
    document.body.replaceChildren()
    localStorage.clear()
    vi.restoreAllMocks()
    vi.useRealTimers()
  })

  it('blocks startup and replay before compliance initializes', async () => {
    const removeSeen = vi.spyOn(Storage.prototype, 'removeItem')
    layout()

    useOnboardingStore().replay()
    await vi.advanceTimersByTimeAsync(1000)

    expect(useAdminComplianceStore().initialized).toBe(false)
    expect(driverMock.create).not.toHaveBeenCalled()
    expect(driverMock.drive).not.toHaveBeenCalled()
    expect(removeSeen).not.toHaveBeenCalled()
  })

  it('blocks while status loads, including cached acknowledged status', async () => {
    await fetchStatus(false)

    let resolveStatus: ((value: AdminComplianceStatus) => void) | undefined
    const response = new Promise<AdminComplianceStatus>((resolve) => {
      resolveStatus = resolve
    })
    vi.mocked(complianceAPI.getStatus).mockReturnValueOnce(response)
    const loading = useAdminComplianceStore().fetchStatus()
    const view = layout()

    await vi.advanceTimersByTimeAsync(1000)

    expect(useAdminComplianceStore().loading).toBe(true)
    expect(driverMock.create).not.toHaveBeenCalled()

    view.unmount()
    if (!resolveStatus) throw new Error('Missing status resolver')
    resolveStatus(status(false))
    await loading
  })

  it('blocks when compliance requires acknowledgement', async () => {
    await fetchStatus(true)
    layout()

    await vi.advanceTimersByTimeAsync(1000)

    expect(useAdminComplianceStore().required).toBe(true)
    expect(driverMock.create).not.toHaveBeenCalled()
  })

  it('blocks after the initial status fetch fails', async () => {
    vi.mocked(complianceAPI.getStatus)
      .mockRejectedValueOnce(new Error('Status unavailable'))

    await expect(useAdminComplianceStore().fetchStatus())
      .rejects.toThrow('Status unavailable')
    layout()
    await vi.advanceTimersByTimeAsync(1000)

    expect(useAdminComplianceStore().initialized).toBe(false)
    expect(useAdminComplianceStore().loading).toBe(false)
    expect(useAdminComplianceStore().status).toBeNull()
    expect(driverMock.create).not.toHaveBeenCalled()
  })

  it('defers automatic startup until acknowledged and starts it once', async () => {
    layout()
    await vi.advanceTimersByTimeAsync(1000)
    expect(driverMock.create).not.toHaveBeenCalled()

    await fetchStatus(false)
    await vi.advanceTimersByTimeAsync(999)
    expect(driverMock.create).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(1)
    expect(driverMock.create).toHaveBeenCalledTimes(1)
    expect(driverMock.drive).toHaveBeenCalledTimes(1)

    useOnboardingStore().getDriverInstance()?.destroy()
    useAdminComplianceStore().requireAcknowledgement()
    await fetchStatus(false)
    await vi.advanceTimersByTimeAsync(1000)

    expect(driverMock.create).toHaveBeenCalledTimes(1)

    // Explicit replay remains available after automatic startup was consumed.
    useOnboardingStore().replay()
    await vi.advanceTimersByTimeAsync(0)
    expect(driverMock.create).toHaveBeenCalledTimes(2)
    expect(driverMock.drive).toHaveBeenCalledTimes(2)
  })

  it('preserves normal users: no automatic tour, but replay works', async () => {
    const user = useAuthStore().user
    if (!user) throw new Error('Missing test user')
    user.role = 'user'

    await fetchStatus(true)
    layout()
    await vi.advanceTimersByTimeAsync(1000)
    expect(driverMock.create).not.toHaveBeenCalled()

    useOnboardingStore().replay()
    await vi.advanceTimersByTimeAsync(0)

    expect(driverMock.drive).toHaveBeenCalledTimes(1)
    expect(getUserSteps).toHaveBeenCalledTimes(1)
    expect(getAdminSteps).not.toHaveBeenCalled()
  })

  it('cancels startup when compliance closes during element preparation', async () => {
    await fetchStatus(false)
    const showTarget = ref(false)
    layout(showTarget)
    await vi.advanceTimersByTimeAsync(1000)

    expect(driverMock.create).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(1)

    useAdminComplianceStore().requireAcknowledgement()
    await vi.advanceTimersByTimeAsync(0)
    expect(vi.getTimerCount()).toBe(0)

    showTarget.value = true
    await nextTick()
    await vi.advanceTimersByTimeAsync(150)
    expect(driverMock.create).not.toHaveBeenCalled()

    await fetchStatus(false)
    await vi.advanceTimersByTimeAsync(1000)
    expect(driverMock.drive).toHaveBeenCalledTimes(1)
  })

  it('rechecks permission after nextTick before creating a driver', async () => {
    const allowed = ref(true)
    const { tour } = hook(() => allowed.value)

    const startup = tour.startTour()
    allowed.value = false
    await startup

    expect(driverMock.create).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('cancels a queued automatic start on unmount', async () => {
    await fetchStatus(false)
    const view = layout()
    view.unmount()

    await vi.advanceTimersByTimeAsync(1000)

    expect(driverMock.create).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('settles an in-flight startup on unmount without advancing its wait', async () => {
    const { view, tour } = hook()
    let settled = false
    const startup = tour.startTour().then(() => {
      settled = true
    })

    await vi.advanceTimersByTimeAsync(0)
    expect(settled).toBe(false)
    expect(vi.getTimerCount()).toBe(1)

    view.unmount()
    await vi.advanceTimersByTimeAsync(0)

    expect(settled).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
    expect(driverMock.create).not.toHaveBeenCalled()
    await startup
  })

  it('preserves an already driven tour across layout unmount', async () => {
    await fetchStatus(false)
    const view = layout()
    await vi.advanceTimersByTimeAsync(1000)

    const active = useOnboardingStore().getDriverInstance()
    expect(active?.isActive()).toBe(true)

    view.unmount()

    expect(useOnboardingStore().getDriverInstance()).toBe(active)
    expect(active?.isActive()).toBe(true)
  })
})
