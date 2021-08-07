##################################################################
## Import-ini                                                   ##
## ----------                                                   ##
## This function will convert an ini to an array table.         ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function Import-Ini
{
    <# 
        .Synopsis
        return ini file content to as array.

        .Description
        By parsing the ini file, will return an array letting script calls its content this way : $YourVar["Section"]["Parameter"]
        
        .Parameter FilePath
        File path to the ini file.

        .Notes
        Version 01.00: 24/08/2019. 
            History: Function creation.
    #>

    ## Parameters 
    Param (
        # Path to the ini file
        [Parameter(Mandatory=$true)]
        [string]
        $FilePath
        )

    ## Generate output variable container
    $ini = @{}
    
    ## Parse the file content and compare it with regular expression
    if (!(Test-Path $FilePath)) 
    { 
        return $null 
        break 
    }
    
    switch -regex -file $FilePath
    {
        # Section
        "^\[(.+)\]"     { $section = $matches[1]
                          $ini[$section] = @{}
                          $CommentCount = 0 
                        }
        # Comment
        "^(;.*)$"       { $value = $matches[1]
                          $CommentCount = $CommentCount + 1
                          $name = "Comment" + $CommentCount
                          $ini[$section][$name] = $value 
                        } 
        # Key
        "(.+?)\s*=(.*)" { $name,$value = $matches[1..2] 
                          $ini[$section][$name] = $value 
                        }
    }    
        
    ## return value
    return $ini
}

Export-ModuleMember -Function *