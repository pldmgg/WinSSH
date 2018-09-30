# Change log

## 0.9.3 (September 30, 2018)

- Added workaround for deleting existing symlinks via Remove-Item. See: https://github.com/powershell/powershell/issues/621

## 0.9.2 (September 15, 2018)

- Minor updates

## 0.9.1 (September 12, 2018)

- Significant updates to Set-DefaultShell function

## 0.9.0 (September 8, 2018)

- Fixed how the installation of pwsh is handled if not already present as determined by Set-DefaultShell
- Added Extract-SSHPrivateKeyFromRegistry function (for keys loaded in ssh-agent that are no longer on filesystem)

## 0.8.9 (August 1, 2018)

- Updated WinCompat Functions

## 0.8.8 (July 23, 2018)

- Updated InvokePSCompatibility Private to improve import speed in PSCore

## 0.8.7 (July 23, 2018)

- Updated InvokeModuleDependencies Private function to ensure Module Dependencies are installed even when function names overlap

## 0.8.6 (July 23, 2018)

- Updated InvokePSCompatibility Private function to ensure Module Dependencies are installed even when function names overlap

## 0.8.5 (July 18, 2018)

- Updated GetModuleDependencies Private function to help Module load faster in PSCore

## 0.8.4 (July 18, 2018)

- Updated README.md

## 0.8.3 (July 18, 2018)

- Added link to GitHub Repo in description

## 0.8.2 (July 18, 2018)

- Initial deployment to PSGallery

## 0.8.1 (May 7, 2018)

- Created

