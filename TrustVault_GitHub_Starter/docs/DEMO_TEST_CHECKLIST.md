# Demo Test Checklist

Use only demo data. Do not enter confidential or personal information.

- [ ] Start the JavaScript server with `node trustvault.js`.
- [ ] Open `http://localhost:3000`.
- [ ] Confirm the dashboard loads.
- [ ] Create a document metadata entry.
- [ ] Check that the document appears in the list.
- [ ] Try the View action and confirm the demo explains that no file content is stored.
- [ ] Try sharing with a valid demo user ID.
- [ ] Try an invalid user ID and verify that the request is rejected.
- [ ] Switch to a different demo identity and inspect the displayed data.
- [ ] Check that actions appear in the audit trail.
- [ ] Stop the server with `Ctrl+C`.
- [ ] Repeat with Python using `python trustvault.py`.

## Important limitations

These checks validate a local prototype only. They do not prove that the app is safe for real users or sensitive files. Demo identity selection is not authentication, and in-memory data resets when the server restarts.
