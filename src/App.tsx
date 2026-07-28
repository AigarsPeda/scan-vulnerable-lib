import { Sidebar } from './components/Sidebar'
import { ProgressView } from './components/ProgressView'
import { ReportView } from './components/ReportView'
import { useScan } from './hooks/useScan'
import iconUrl from '../assets/icon.png'
import './styles/app.css'

export default function App() {
  const scan = useScan()

  return (
    <div className="shell">
      <Sidebar
        iconUrl={iconUrl}
        scanState={scan.scanState}
        statusLabel={scan.statusLabel}
        statusTone={scan.statusTone}
        tab={scan.tab}
        onSelectTab={scan.selectTab}
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
      </main>
    </div>
  )
}
