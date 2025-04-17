Get-AzPolicyAssignment | Select-Object -Property Scope, PolicyDefinitionID, DisplayName | where-object displayname = "CIS Microsoft Azure Foundations Benchmark v2.0.0"

#send output to Word
Install-Module -Name PSWriteWord 

##### Run under windows platform as it calls .NET COM objects########################
#$word = New-Object -ComObject Word.Application
#$word.Visible = $true #Optional: to make the Word application visible
#$document = $word.Documents.Add()
#$selection = $word.Selection
#$selection.TypeText("Hello, world!")
#$selection.TypeParagraph()
#$selection.TypeText("This is a new paragraph.")
#$document.SaveAs("output.docx")
#$word.Quit()
#####################################################################################

# $hash value gets replaced in the word document

$objWord = New-Object -ComObject word.application
$objWord.Visible = $True
$objDoc = $objWord.Documents.Open("Path")
$objSelection = $objWord.Selection

function wordSearch($currentValue, $replaceValue){
    $objSelection = $objWord.Selection
    $FindText = $currentValue
    $MatchCase = $false
    $MatchWholeWord = $true
    $MatchWildcards = $false
    $MatchSoundsLike = $false
    $MatchAllWordForms = $false
    $Forward = $true
    $wrap = $wdFindContinue
    $wdFindContinue = 1
    $Format = $false
    $ReplaceWith = $hash[$value]
    $ReplaceAll = 2

    $objSelection.Find.Execute($FindText, $MatchCase, $MatchWholeWord, $MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $wrap, $Format, $ReplaceWith, $ReplaceAll)
    }

$hash = @{"<First Name>" = "Value1"; "<Last Name>"="Value2"; "<Job>"="Value3"}

foreach($value in $hash.Keys) {
    $currentValue = $value
    $replaceValue = $hash[$value]

    wordSearch $currentValue $replaceValue

    }