---
trigger: always_on
---

C/C++ Coding Standards
Bracing Style
Always use Allman style bracing (braces on a new line).

Do not use K&R style (braces on the same line).

Mandatory Braces: Braces are required for all control structures (if, else, for, while, etc.), even if they contain only a single statement.

Indentation Style
Use 4 spaces for indentation.

Code within braces must be indented by one level (4 spaces).

Examples
Control Structures (Standard)
C++
// Good
if (condition) 
{
    // code
}

// Bad
if (condition) {
    // code
}
Single-Line Statements
Even single-statement blocks must be broken into multiple lines with proper bracing and indentation.

C++
// Good
if (!continuon)
{
    return VALUE;
}

// Bad
if (!continuon) { return VALUE; }

// Bad
if (!continuon) return VALUE;