@echo off

if "%OS%" == "Windows_NT" setlocal
rem ---------------------------------------------------------------------------
rem Start/Stop Script
rem

if not "%JRE_HOME%" == "" goto gotJreHome
if not "%JAVA_HOME%" == "" goto gotJavaHome
echo Neither the JAVA_HOME nor the JRE_HOME environment variable is defined
echo At least one of these environment variable is needed to run this program
goto exit

:needJavaHome
rem Check if we have a usable JDK
if "%JAVA_HOME%" == "" goto noJavaHome
if not exist "%JAVA_HOME%\bin\java.exe" goto noJavaHome
if not exist "%JAVA_HOME%\bin\javaw.exe" goto noJavaHome
set "JRE_HOME=%JAVA_HOME%"
goto okJava

:noJavaHome
echo The JAVA_HOME environment variable is not defined correctly.
goto exit

:gotJavaHome
rem No JRE given, use JAVA_HOME as JRE_HOME
set "JRE_HOME=%JAVA_HOME%"

:gotJreHome
rem Check if we have a usable JRE
if not exist "%JRE_HOME%\bin\java.exe" goto noJreHome
if not exist "%JRE_HOME%\bin\javaw.exe" goto noJreHome
goto okJava

:noJreHome
rem Needed at least a JRE
echo The JRE_HOME environment variable is not defined correctly
echo This environment variable is needed to run this program
goto exit

:okJava
rem Set standard command for invoking Java.
rem Also note the quoting as JAVA_HOME may contain spaces.
set _RUNJAVA="%JRE_HOME%\bin\java"

echo %_RUNJAVA%

rem Deal with classpath

cd ..

set "CLASSPATH=target\bracket-properties-1.3.6.jar"
set "CLASSPATH=%CLASSPATH%;target\jackson-core-2.2.3.jar"
set "CLASSPATH=%CLASSPATH%;target\jackson-databind-2.2.3.jar"
set "CLASSPATH=%CLASSPATH%;target\jackson-annotations-2.2.3.jar"
set "CLASSPATH=%CLASSPATH%;target\buttermilk-core-1.0.0.jar"
set "CLASSPATH=%CLASSPATH%;target\base64-2.3.8.jar"
set "CLASSPATH=%CLASSPATH%;target\bTLS-1.0.0.jar"
set "CLASSPATH=%CLASSPATH%;target\protobuf-java-2.5.0.jar"
set "CLASSPATH=%CLASSPATH%;target\protocol-buffers-1.0.0.jar"
set "CLASSPATH=%CLASSPATH%;target\client-storage-1.0.0.jar"
set "CLASSPATH=%CLASSPATH%;target\je-6.0.11.jar"
set "CLASSPATH=%CLASSPATH%;target\log4j-api-2.1.jar"
set "CLASSPATH=%CLASSPATH%;target\log4j-core-2.1.jar"
set "CLASSPATH=%CLASSPATH%;target\test-classes

echo %CLASSPATH%

set MAINCLASS=com.cryptoregistry.btls.server.MTEchoServer
set "JAVA_OPTS=-Xmx1024m"

%_RUNJAVA% %JAVA_OPTS% -classpath "%CLASSPATH%" %MAINCLASS% %*

:end
