<?php

use Illuminate\Support\Facades\Route;

/*
| LumosBlog routes. A small marketing site + an internal "draft preview" link
| a developer left wired up.
*/

Route::get('/', function () {
    return view('welcome');
});

// Internal draft preview. BUG: no existence check — an unknown slug throws, and with
// APP_DEBUG=true the full stack trace is rendered to the browser (the Ignition page).
Route::get('/preview/{slug}', function ($slug) {
    $drafts = [
        'launch' => 'Launch announcement — Q4',
        'notes'  => 'Release notes v3.4',
    ];

    if (!array_key_exists($slug, $drafts)) {
        throw new \RuntimeException("Unknown draft requested: {$slug}");
    }

    return view('welcome', ['draft' => $drafts[$slug]]);
});
