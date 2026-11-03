@echo off
echo ===============================================================================
echo   PUSHING ETHICAL HACKING PORTFOLIO TO GITHUB
echo ===============================================================================
echo Target Repository: https://github.com/mid841098/ethical-hacking-lab
echo Branch: main
echo.
git push -u origin main
if %ERRORLEVEL% equ 0 (
    echo.
    echo [SUCCESS] Repository pushed successfully!
    echo Your public submission link: https://github.com/mid841098/ethical-hacking-lab
) else (
    echo.
    echo [NOTICE] If the push failed with "Repository not found", make sure you have created
    echo the empty repository at: https://github.com/new?name=ethical-hacking-lab
    echo (Leave "Initialize this repository with a README" UNCHECKED, then click "Create repository").
)
echo.
pause
