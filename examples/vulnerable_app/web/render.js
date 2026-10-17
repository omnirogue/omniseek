// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The OmniSeek Authors
// Deliberately flawed demo code for the OmniSeek examples.

export function renderComment(container, comment) {
  container.innerHTML = `<p class="comment">${comment.body}</p>`;
}

export async function saveAll(items, api) {
  items.forEach(async (item) => {
    await api.save(item);
  });
}

export function cloneState(state) {
  return JSON.parse(JSON.stringify(state));
}
