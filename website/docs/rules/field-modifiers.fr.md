# Modificateurs de champ pris en charge

## Modificateurs de champ pris en charge par Hayabusa
| Field Modifier                |   Sigma Count |   Hayabusa Count |
|:------------------------------|--------------:|-----------------:|
| all                           |            13 |                0 |
| base64offsetǀcontains         |             7 |                0 |
| base64ǀcontains               |             1 |                0 |
| cased                         |             0 |                0 |
| cidr                          |            35 |                0 |
| contains                      |          3070 |               21 |
| containsǀall                  |          1081 |                0 |
| containsǀcased                |             0 |                0 |
| containsǀexpand               |             1 |                0 |
| containsǀwindash              |           108 |                0 |
| endswith                      |          3253 |              273 |
| endswithfield                 |             0 |                0 |
| endswithǀcased                |             0 |                0 |
| endswithǀwindash              |             2 |                0 |
| equalsfield                   |             0 |                0 |
| exists                        |             0 |                0 |
| expand                        |            11 |                0 |
| fieldref                      |             2 |                1 |
| fieldrefǀcontains             |             0 |                0 |
| fieldrefǀendswith             |             0 |                2 |
| fieldrefǀstartswith           |             0 |                0 |
| gt                            |             0 |                0 |
| gte                           |             0 |                0 |
| lt                            |             0 |                0 |
| lte                           |             0 |                0 |
| re                            |           188 |               11 |
| reǀi                          |             1 |                0 |
| reǀm                          |             0 |                0 |
| reǀs                          |             0 |                0 |
| startswith                    |           535 |                6 |
| startswithǀcased              |             0 |                0 |
| utf16beǀbase64offsetǀcontains |             0 |                0 |
| utf16leǀbase64offsetǀcontains |             0 |                0 |
| utf16ǀbase64offsetǀcontains   |             0 |                0 |
| wideǀbase64offsetǀcontains    |             2 |                0 |

## Modificateurs de champ non pris en charge par Hayabusa
Actuellement, tout est pris en charge.

## Règles de corrélation prises en charge par Hayabusa
| Correlation Rule                 |   Sigma Count |   Hayabusa Count |
|:---------------------------------|--------------:|-----------------:|
| event_count                      |             0 |                0 |
| event_count (with group-by)      |             0 |                1 |
| temporal                         |             0 |                0 |
| temporal (with group-by)         |             0 |                0 |
| temporal_ordered                 |             0 |                0 |
| temporal_ordered (with group-by) |             0 |                0 |
| value_count                      |             0 |                0 |
| value_count (with group-by)      |             0 |                2 |

## Règles de corrélation non prises en charge par Hayabusa
Actuellement, tout est pris en charge.

Ce document est mis à jour dynamiquement en fonction des dernières règles.  
Dernière mise à jour : 2026/04/28  
Auteur : Fukusuke Takahashi
