/*
 @licstart  The following is the entire license notice for the JavaScript code in this file.

 The MIT License (MIT)

 Copyright (C) 1997-2020 by Dimitri van Heesch

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute,
 sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or
 substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 @licend  The above is the entire license notice for the JavaScript code in this file
*/
var NAVTREE =
[
  [ "libcdoc", "index.html", [
    [ "Introduction to libcdoc", "index.html", "index" ],
    [ "Overview of libcdoc", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2overview.html", [
      [ "Key Features", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2overview.html#autotoc_md6", null ],
      [ "Library Architecture", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2overview.html#autotoc_md7", [
        [ "Core Components", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2overview.html#autotoc_md8", null ],
        [ "Extensibility", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2overview.html#autotoc_md9", null ],
        [ "Multi-Language Support with SWIG", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2overview.html#autotoc_md10", null ]
      ] ],
      [ "Interoperability", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2overview.html#autotoc_md11", null ]
    ] ],
    [ "Basic libcdoc Library Usage", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html", [
      [ "CDOC1 vs. CDOC2 Formats", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md14", null ],
      [ "Common", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md16", null ],
      [ "Encryption", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md18", [
        [ "Workflow Diagram", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md19", null ],
        [ "CryptoBackend", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md21", [
          [ "<tt>getSecret</tt>", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md22", null ],
          [ "<tt>getKeyMaterial</tt>", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md23", null ],
          [ "<tt>extractHKDF</tt>", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md24", null ]
        ] ],
        [ "NetworkBackend", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md26", [
          [ "<tt>getClientTLSCertificate</tt>", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md27", null ],
          [ "<tt>getPeerTLSCertificates</tt>", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md28", null ],
          [ "<tt>signTLS</tt>", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md29", null ]
        ] ],
        [ "Configuration", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md31", [
          [ "<tt>getValue</tt>", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md32", null ]
        ] ],
        [ "CDocWriter", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md34", [
          [ "Workflow", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md35", null ]
        ] ],
        [ "Implementation Example", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md37", null ]
      ] ],
      [ "Decryption", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md39", [
        [ "Workflow Diagram", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md40", null ],
        [ "CryptoBackend", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md42", null ],
        [ "NetworkBackend", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md44", null ],
        [ "Configuration", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md46", null ],
        [ "CDocReader", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md48", [
          [ "Workflow", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md49", null ]
        ] ],
        [ "Implementation Example", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2usage.html#autotoc_md51", null ]
      ] ]
    ] ],
    [ "libcdoc Tool Usage", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2tool.html", [
      [ "Encryption", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2tool.html#autotoc_md55", [
        [ "Options", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2tool.html#autotoc_md56", null ],
        [ "Recipients", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2tool.html#autotoc_md57", null ],
        [ "Examples", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2tool.html#autotoc_md58", null ]
      ] ],
      [ "Decryption", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2tool.html#autotoc_md60", [
        [ "Options", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2tool.html#autotoc_md61", null ],
        [ "Examples", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2tool.html#autotoc_md62", null ]
      ] ],
      [ "Viewing Locks", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2tool.html#autotoc_md64", [
        [ "Example", "md__2home_2runner_2work_2libcdoc_2libcdoc_2doc_2tool.html#autotoc_md65", null ]
      ] ]
    ] ],
    [ "Namespace Members", "namespacemembers.html", [
      [ "All", "namespacemembers.html", null ],
      [ "Functions", "namespacemembers_func.html", null ],
      [ "Typedefs", "namespacemembers_type.html", null ],
      [ "Enumerations", "namespacemembers_enum.html", null ],
      [ "Enumerator", "namespacemembers_eval.html", null ]
    ] ],
    [ "Classes", "annotated.html", [
      [ "Class List", "annotated.html", "annotated_dup" ],
      [ "Class Index", "classes.html", null ],
      [ "Class Hierarchy", "hierarchy.html", "hierarchy" ],
      [ "Class Members", "functions.html", [
        [ "All", "functions.html", "functions_dup" ],
        [ "Functions", "functions_func.html", "functions_func" ],
        [ "Variables", "functions_vars.html", null ],
        [ "Enumerations", "functions_enum.html", null ],
        [ "Enumerator", "functions_eval.html", null ]
      ] ]
    ] ]
  ] ]
];

var NAVTREEINDEX =
[
"annotated.html",
"structlibcdoc_1_1IStreamSource.html#a1b1f47a830d6c9313249854de0f3b7d1"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';