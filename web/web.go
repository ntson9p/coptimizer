// Package web is the browser side of COptimizer: plain HTML, CSS and
// JavaScript modules, embedded into the exe. Every text shown lives in
// i18n/en.json.
package web

import "embed"

// Files are the web page's files, with index.html at the top.
//
//go:embed index.html css js i18n
var Files embed.FS
