import { TestBed } from '@angular/core/testing';

import { Aria } from './aria';

describe('Aria', () => {
  let service: Aria;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(Aria);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
