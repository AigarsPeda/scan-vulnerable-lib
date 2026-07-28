import { AnimatePresence, motion } from 'motion/react'
import { Sidebar } from './components/Sidebar'
import { ProgressView } from './components/ProgressView'
import { ReportView } from './components/ReportView'
import { useScan } from './hooks/useScan'
import iconUrl from '../assets/icon.png'
import './styles/app.css'

const slideTransition = {
  duration: 0.3,
  ease: [0.22, 1, 0.36, 1] as const,
}

export default function App() {
  const scan = useScan()
  // 1 = Progress → Report (out left / in from right)
  // -1 = Report → Progress (out right / in from left)
  const direction = scan.tab === 'report' ? 1 : -1

  return (
    <div className="shell">
      <Sidebar
        iconUrl={iconUrl}
        scanState={scan.scanState}
        statusLabel={scan.statusLabel}
        statusTone={scan.statusTone}
        tab={scan.tab}
        onSelectTab={scan.selectTab}
        optionsLocked={scan.optionsLocked}
        highOnly={scan.highOnly}
        skipCache={scan.skipCache}
        skipOsv={scan.skipOsv}
        maxProjects={scan.maxProjects}
        rootPath={scan.rootPath}
        onHighOnly={scan.setHighOnly}
        onSkipCache={scan.setSkipCache}
        onSkipOsv={scan.setSkipOsv}
        onMaxProjects={scan.setMaxProjects}
        onRootPath={scan.setRootPath}
        onPrimaryClick={scan.onPrimaryClick}
        onStop={scan.stopScan}
        onPickFolder={scan.pickFolder}
      />

      <main className="main">
        <AnimatePresence initial={false} custom={direction}>
          <motion.div
            key={scan.tab}
            className="view-pane"
            custom={direction}
            variants={{
              enter: (d: number) => ({ x: `${100 * d}%` }),
              center: { x: 0 },
              exit: (d: number) => ({ x: `${-100 * d}%` }),
            }}
            initial="enter"
            animate="center"
            exit="exit"
            transition={slideTransition}
          >
            {scan.tab === 'scan' ? (
              <ProgressView
                phase={scan.phase}
                detail={scan.detail}
                percent={scan.percent}
                findings={scan.findings}
                findingCount={scan.findingCount}
                events={scan.events}
                onClearEvents={scan.clearEvents}
              />
            ) : (
              <ReportView
                findings={scan.reportFindings}
                findingCount={scan.findingCount}
                scanState={scan.scanState}
                phase={scan.phase}
                percent={scan.percent}
                onExport={scan.exportReport}
              />
            )}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  )
}
