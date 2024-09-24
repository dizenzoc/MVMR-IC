import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HomepageComponent } from "./homepage/homepage.component";

import { FormsModule, ReactiveFormsModule } from '@angular/forms';

import { NgbModule } from '@ng-bootstrap/ng-bootstrap';

import { MatSidenavModule } from '@angular/material/sidenav';
import { MatIconModule } from '@angular/material/icon';
import { MatDividerModule } from '@angular/material/divider';
import { MatListModule } from '@angular/material/list';
import { MatCardModule } from '@angular/material/card'
import { IonicModule, IonicRouteStrategy } from '@ionic/angular';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { HttpClientModule } from '@angular/common/http';
import { DxDataGridModule } from 'devextreme-angular';
import {MatProgressBarModule} from '@angular/material/progress-bar';
import { ErrorComponent } from './error/error.component';



@NgModule({
  declarations: [
    HomepageComponent,
    ErrorComponent
  ],
  imports: [
    CommonModule,
    NgbModule,
    FormsModule,
    HttpClientModule,
    ReactiveFormsModule,
    FontAwesomeModule,
    IonicModule.forRoot(),
    MatSidenavModule,
    MatIconModule,
    MatDividerModule,
    MatListModule,
    MatCardModule,
    DxDataGridModule,
    MatProgressBarModule,
  ],
  exports: [      //Necessario per rendere la componente visibile anche all'esterno (es. App-Module.ts)
    HomepageComponent,
    ErrorComponent
  ]
})
export class FeaturesModule { }
