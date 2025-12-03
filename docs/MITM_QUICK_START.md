# MITM Attack Demonstration - Quick Start

## Running the MITM Demonstration

### Method 1: Run the Script (Recommended)

```powershell
# From project root (D:\infosec)
node scripts/run-mitm-demonstration.js
```

This will:
- Run both attack scenarios
- Generate packet captures
- Create evidence files in `logs/` directory

### Method 2: Run Tests

```powershell
# From client directory
cd client
npm run test:attacks -- mitm_attack_demonstration.test.js
```

### Troubleshooting

**Issue**: `Cannot find module '@peculiar/webcrypto'`

**Solution**: Install dependencies at root level:
```powershell
npm install
```

**Issue**: Script runs but produces no output

**Solution**: Check that crypto polyfill is set up correctly. The script should show:
```
MITM ATTACK DEMONSTRATION RUNNER
================================================================================
```

**Issue**: Tests fail with "crypto is not defined"

**Solution**: Make sure you're running from the client directory and using jest:
```powershell
cd client
npm run test:attacks
```

## Expected Output

After running successfully, you should see:

1. **Console Output**: Summary of both attacks
2. **Files Created** in `logs/`:
   - `mitm_attack1_packets.txt` - Attack 1 packet log
   - `mitm_attack1_packets.json` - Attack 1 JSON
   - `mitm_attack2_packets.txt` - Attack 2 packet log
   - `mitm_attack2_packets.json` - Attack 2 JSON
   - `mitm_demonstration_report.json` - Full report
   - `mitm_demonstration_summary.txt` - Summary

## Verification

Check that:
- ✅ Attack 1 shows "Attack Successful: YES"
- ✅ Attack 2 shows "Attack Successful: NO"
- ✅ Packet logs are generated
- ✅ Evidence files are created

For detailed information, see `MITM_ATTACK_DEMONSTRATION_REPORT.md`

