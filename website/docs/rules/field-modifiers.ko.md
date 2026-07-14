# 지원되는 필드 수정자(Field Modifier)

## Hayabusa가 지원하는 필드 수정자
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

## Hayabusa가 지원하지 않는 필드 수정자
현재 모든 항목이 지원됩니다.

## Hayabusa가 지원하는 상관관계 규칙(Correlation Rule)
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

## Hayabusa가 지원하지 않는 상관관계 규칙
현재 모든 항목이 지원됩니다.

이 문서는 최신 규칙을 기반으로 동적으로 업데이트되고 있습니다.  
Last Update: 2026/04/28  
Author: Fukusuke Takahashi
