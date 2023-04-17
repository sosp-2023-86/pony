
// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once
#include <string>

// Sets OS-specific process title information based on the command line. This
// does nothing if the OS doesn't support or need this capability.
//
// Pass in the argv from main(). On Windows, where there is no argv, you can
// pass null or just don't call this function, since it does nothing. This
// argv pointer will be cached so if you call this function again, you can pass
// null in the second call. This is to support the case where it's called once
// at startup, and later when a zygote is fork()ed. The later call doesn't have
// easy access to main's argv.
//
// On non-Mac Unix platforms, we exec ourselves from /proc/self/exe, but that
// makes the process name that shows up in "ps" etc. for the child processes
// show as "exe" instead of "chrome" or something reasonable. This function
// will try to fix it so the "effective" command line shows up instead.

namespace dory::third_party::setproctitle {
void SetProcessTitleFromCommandLine(int argc, const char** argv,
                                    std::string const& short_name_suffix = {});
}
