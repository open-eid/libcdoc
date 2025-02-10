/*
 * libcdoc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __EXPORTS_H__
#define __EXPORTS_H__

#ifdef WIN32
  #include <winapifamily.h>
  
  #ifdef CDOC_DYNAMIC_LINK
    // Create or use dynamic link library
    #ifdef cdoc_EXPORTS
	  #define CDOC_EXPORT __declspec(dllexport)
    #else
	  #define CDOC_EXPORT __declspec(dllimport)
    #endif
  #else
    // Create or use static link library
    #define CDOC_EXPORT
  #endif
  
  #if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
	#define CDOC_DEPRECATED __declspec(deprecated)
  #else
	#define CDOC_DEPRECATED
  #endif
  #if _MSC_VER >= 1900
	#define CDOC_NOEXCEPT noexcept
  #else
	#define CDOC_NOEXCEPT
  #endif
  #define CDOC_WARNING_PUSH __pragma(warning(push))
  #define CDOC_WARNING_POP __pragma(warning(pop))
  #define CDOC_WARNING_DISABLE_CLANG(text)
  #define CDOC_WARNING_DISABLE_GCC(text)
  #define CDOC_WARNING_DISABLE_MSVC(number) __pragma(warning(disable: number))
  #define STDCALL __stdcall
  #pragma warning( disable: 4251 ) // shut up std::vector warnings
#else
  #define CDOC_EXPORT __attribute__ ((visibility("default")))
  #define CDOC_DEPRECATED __attribute__ ((__deprecated__))
  #define CDOC_NOEXCEPT noexcept
  #define CDOC_DO_PRAGMA(text) _Pragma(#text)
  #define CDOC_WARNING_PUSH CDOC_DO_PRAGMA(GCC diagnostic push)
  #define CDOC_WARNING_POP CDOC_DO_PRAGMA(GCC diagnostic pop)
  #if __clang__
  #define CDOC_WARNING_DISABLE_CLANG(text) CDOC_DO_PRAGMA(clang diagnostic ignored text)
  #else
  #define CDOC_WARNING_DISABLE_CLANG(text)
  #endif
  #define CDOC_WARNING_DISABLE_GCC(text) CDOC_DO_PRAGMA(GCC diagnostic ignored text)
  #define CDOC_WARNING_DISABLE_MSVC(text)
  #define STDCALL
#endif

#endif // EXPOORTS_H
