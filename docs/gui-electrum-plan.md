# Electrum GUI Plan (Option C - Hybrid Dashboard)

## Goals
- Deliver a sleek, modern dashboard that balances real-time telemetry with actionable controls.
- Reuse existing backend components (`ConfigManager`, `NetworkManager`, `RewardSystem`, `BitcoinWallet`, `ElectrumClient`, `ResourceMonitor`).
- Keep dependency footprint manageable (Qt 6 Widgets + Charts, no QML for v1).

## Visual Language
- Hybrid dark theme with accent color derived from reward status (default hex `#3AAFA9`).
- Rounded cards, subtle drop shadows, typography using `Segoe UI`/`Roboto`.
- Responsive layout targeting 1280x720 minimum; supports collapse to sidebar.

## Layout Overview
1. **Top Bar**
   - Left: Application logo + puzzle number selector.
   - Center: Global status pill (Coordinator, Worker, Idle) with Electrum connection indicator.
   - Right: Reward address drop-down and quick actions (Start, Stop, Auto).
2. **Primary Tabs (tabbed widget)**
   - `Dashboard`: Summary tiles + resource charts.
   - `Workflows`: Chunk queue, assignment timeline, auto-continue toggles.
   - `Wallet`: Electrum connectivity, balances, payout previews.
   - `Network`: Peer list, consensus gauge, recent messages.
   - `Logs`: Structured log viewer with filters.
3. **Footer**
   - GPU/CPU utilization mini-bars, build hash, config profile indicator.

## Panel Details
### Dashboard Tab
- **Status Tiles**: Current puzzle, processed keys/sec, confirmed chunks, reward accrued.
- **Charts**: Dual-axis line chart for CPU/GPU load using `QtCharts::QChartView`.
- **Alerts**: Inline list for auto-suspend, resource throttling.

### Workflows Tab
- **Chunk Table**: `QTableView` showing assigned, in-progress, completed ranges.
- **Actions**: Buttons for `initwork`, `setreward`, `work` status refresh.
- **Scheduler Card**: Displays chunk size, backlog, ledger sync indicator.

### Wallet Tab
- **Electrum Card**: Server list (combo box), connection status, latency.
- **Balance Widget**: Confirmed/unconfirmed balances, reward split sliders.
- **PSBT Controls**: Buttons to create payout PSBT, review contributions.

### Network Tab
- **Peer Graph**: `QListWidget` or custom view for connected peers with latency badges.
- **Consensus Widget**: Shows current tip hash, vote weights, `CONTRIB` summaries.
- **Message Feed**: Scroll area for protocol verbs (WORKREQ/WORKASSIGN/...).

### Logs Tab
- **Filter Bar**: Severity dropdown, text search, pause/resume capture.
- **Log Table**: Binds to `Logger` output via signal forwarding.

## Data & Events
- `MainWindow` subscribes to backend signals via lightweight bus:
  - `NetworkManager::onPeerUpdate`
  - `WorkCoordinator::onChunkStatus`
  - `BitcoinWallet::onElectrumStatus`
  - `ResourceMonitor::onMetrics`
- Add `GuiEventBridge` (QObject) to translate std::function callbacks into Qt signals.
- All UI updates dispatched via `QMetaObject::invokeMethod` to stay on GUI thread.

## Implementation Steps
1. **Qt Scaffolding**
   - Ensure Qt6 Widgets/Charts are located (`find_package(Qt6 COMPONENTS Widgets Charts Network)`).
   - Add `gui/` subdirectory with `MainWindow`, `DashboardWidget`, etc.
   - Guard with `GUI_AVAILABLE` as in root `CMakeLists.txt`.
2. **Event Bridge**
   - Implement `GuiEventBridge` hooking into backend managers, exposing Qt signals.
3. **Widgets**
   - Build modular widgets per tab; use MVC with `QAbstractTableModel` for chunk/peer tables.
4. **Theming**
   - Provide `:/themes/hybrid.qss` stylesheet loaded at startup; allow theme toggle via `Config.ui`.
5. **Testing Hooks**
   - Add `GuiMockData` to simulate backend updates when running `--gui --mock`.
6. **Build Integration**
   - Extend `build.bat` instructions to mention Qt requirement when GUI enabled.
   - Provide `cmake -S . -B build_vs2022 -G "Visual Studio 17 2022" -A x64 -DQT_DIR=<path>` example.

## Dependency Checklist
- Qt 6.5+ (Widgets, Charts, Network modules).
- Existing CUDA/OpenCL (already optional).
- Catch2 optional for tests via `-DBITCRACK_FORCE_FETCH_CATCH2=ON`.

## Validation Plan
1. Install Qt (MSVC 64-bit) and set `Qt6_DIR`.
2. Configure with GUI: `cmake -S . -B build_vs2022 -G "Visual Studio 17 2022" -A x64 -DBITCRACK_ENABLE_GUI=ON` (default is already `ON`, but pass it explicitly when scripting).
3. Run `cmake --build build_vs2022 --config Release`.
4. Launch `build_vs2022\bitcrack-distributed.exe --gui --mock` to verify widgets.
5. Bundle Qt redistributables via `pwsh -File scripts/package_windows.ps1 -Configuration Release` (runs `windeployqt` under the hood) or `macdeployqt` on macOS.
6. Execute tests (with Catch2 fetched) to ensure backend unaffected.

## Future Enhancements
- Optional QML skin once telemetry stabilizes.
- WebSocket bridge for remote monitoring.
- Theme presets synced to Electrum status (online/offline/alert).
