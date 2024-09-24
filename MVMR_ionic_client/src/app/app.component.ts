import { HttpClient } from '@angular/common/http';
import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { MainService } from './service/main.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'MVMR_client';

  constructor(private mainService : MainService, protected http : HttpClient, private router : Router) { 
  }


  ai(){

    //Seconda chiamata per la fase 2: Nightmare (Web Harvesting) per il data integration passando il filename del report ottenuto dalla chiamata getXMLFiles (fine step 1)
    let body = {
      z_summary_filename : 'z_summary_0.json'
    }

    this.http.post<any>(this.mainService.baseURL+'/ai/',body)
    .subscribe( (response:any) => {
      console.log('NLP response',response);
    }, error => {
      console.log('NLP error',error)
    })

  }


  bayesianClassifier(){
    //Seconda chiamata per la fase 2: Nightmare (Web Harvesting) per il data integration passando il filename del report ottenuto dalla chiamata getXMLFiles (fine step 1)
    let body = {}

    this.http.post<any>(this.mainService.baseURL+'/ai/bayesianClassifierTest',body)
    .subscribe( (response:any) => {
      console.log('NLP classifier accuracy: ',response);
    }, error => {
      console.log('NLP error',error)
    })
  }

}
