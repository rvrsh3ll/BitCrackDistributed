#pragma once

#include <QtGlobal>

#if defined(BITCRACKGUI_STATIC)
  // Static library (gui/CMakeLists.txt, BITCRACK_GUI_SHARED=OFF): no decoration.
  #define BITCRACKGUI_API
#elif defined(_WIN32) || defined(_WIN64)
  #if defined(BUILDING_BITCRACKGUI)
    #define BITCRACKGUI_API Q_DECL_EXPORT
  #else
    #define BITCRACKGUI_API Q_DECL_IMPORT
  #endif
#else
  #define BITCRACKGUI_API
#endif
