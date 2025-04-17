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