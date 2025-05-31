<?php
 {
    "functions": {
        //tất cả các file nàm trong thư mục api trả về môi trg php 0.7.3
        //
      "api/**": { "runtime": "vercel-php@0.7.3" }
    },
    //route để nhập đường link trên urlurl
    "routes": [
      { "src": "/api/(.*)", "dest": "/api/$1" }
    ]
    
}